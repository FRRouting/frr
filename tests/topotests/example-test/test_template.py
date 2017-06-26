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

import os
import sys
import pytest

# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

# Required to instantiate the topology builder class.
from mininet.topo import Topo

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))

class TemplateTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Example
        #
        # Create 2 routers
        for routern in range(1, 3):
            tgen.add_router('r{}'.format(routern))

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Create a connection between r1 and r2
        switch = tgen.add_switch('s2')
        switch.add_link(tgen.gears['r1'])
        switch.add_link(tgen.gears['r2'])

def setup_module(_m):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(TemplateTopo)
    # ... and here it calls Mininet initialization functions.
    # When deploying tests, please remove the debug logging level.
    tgen.start_topology('debug')

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            # Uncomment next line to load configuration from ./router/zebra.conf
            #os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

def teardown_module(_m):
    "Teardown the pytest environment"
    tgen = get_topogen()
    # This function tears down the whole topology.
    tgen.stop_topology()

def test_call_mininet_cli():
    "Dummy test that just calls mininet CLI so we can interact with the build."
    tgen = get_topogen()
    tgen.mininet_cli()

if __name__ == '__main__':
    sys.exit(pytest.main(["-s"]))
