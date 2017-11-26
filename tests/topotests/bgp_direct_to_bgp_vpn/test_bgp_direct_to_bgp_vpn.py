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
test_mpls_vpn_topo1.py: Simple FRR/Quagga MPLS VPN Test

                  |
             +----+----+
             |   ce1   |
             | 99.0.0.1|                              CE Router
             +----+----+
       192.168.1. | .2  ce1-eth0
                  | .1  r1-eth4
             +---------+
             |    r1   |
             | 1.1.1.1 |                              PE Router
             +----+----+
                  | .1  r1-eth0
                  |
            ~~~~~~~~~~~~~
          ~~     sw0     ~~
          ~~ 10.0.1.0/24 ~~
            ~~~~~~~~~~~~~
                  |10.0.1.0/24
                  |
                  | .2  r2-eth0
             +----+----+
             |    r2   |
             | 2.2.2.2 |                              P router
             +--+---+--+
    r2-eth2  .2 |   | .2  r2-eth1
         ______/     \______
        /                   \
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
~~     sw2     ~~    ~~     sw1     ~~
~~ 10.0.3.0/24 ~~    ~~ 10.0.2.0/24 ~~
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
        |                 /    |
         \      _________/     |
          \    /                \
r3-eth1 .3 |  | .3  r3-eth0      | .4 r4-eth0
      +----+--+---+         +----+----+
      |     r3    |         |    r4   |
      |  3.3.3.3  |         | 4.4.4.4 |               PE Routers
      +-----------+         +---------+
 192.168.1. | .1     192.168.1.  | .1    rX-eth4
            | .2                 | .2    ceX-eth0
      +-----+-----+         +----+-----+
      |    ce2    |         |   ce3    |
      | 99.0.0.2  |         | 99.0.0.3 |              CE Routers
      +-----+-----+         +----+-----+
            |                    |

"""

import os
import sys
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
sys.path.append(os.path.join(CWD, '../utilities'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lutil import luStart, luInclude, luFinish, luNumFail

# Required to instantiate the topology builder class.
from mininet.topo import Topo

class TemplateTopo(Topo):
    "Test topology builder"
    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # This function only purpose is to define allocation and relationship
        # between routers, switches and hosts.
        #
        # Create P/PE routers
        for routern in range(1, 5):
            tgen.add_router('r{}'.format(routern))
        # Create CE routers
        for routern in range(1, 4):
            tgen.add_router('ce{}'.format(routern))

        #CE/PE links
        tgen.add_link(tgen.gears['ce1'], tgen.gears['r1'], 'ce1-eth0', 'r1-eth4')
        tgen.add_link(tgen.gears['ce2'], tgen.gears['r3'], 'ce2-eth0', 'r3-eth4')
        tgen.add_link(tgen.gears['ce3'], tgen.gears['r4'], 'ce3-eth0', 'r4-eth4')

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = {}
        switch[0] = tgen.add_switch('sw0')
        switch[0].add_link(tgen.gears['r1'], nodeif='r1-eth0')
        switch[0].add_link(tgen.gears['r2'], nodeif='r2-eth0')

        switch[1] = tgen.add_switch('sw1')
        switch[1].add_link(tgen.gears['r2'], nodeif='r2-eth1')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth0')
        switch[1].add_link(tgen.gears['r4'], nodeif='r4-eth0')

        switch[1] = tgen.add_switch('sw2')
        switch[1].add_link(tgen.gears['r2'], nodeif='r2-eth2')
        switch[1].add_link(tgen.gears['r3'], nodeif='r3-eth1')

def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(TemplateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
        config = os.path.join(CWD, '{}/zebra.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_ZEBRA, config)
        config = os.path.join(CWD, '{}/ospfd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_OSPF, config)
        config = os.path.join(CWD, '{}/ldpd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_LDP, config)
        config = os.path.join(CWD, '{}/bgpd.conf'.format(rname))
        if os.path.exists(config):
            router.load_config(TopoRouter.RD_BGP, config)

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()

def no_test_call_mininet_cli():
    "Dummy test that just calls mininet CLI so we can interact with the build."
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info('calling mininet CLI')
    tgen.mininet_cli()

def test_run_lu_tests():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears['r1']
    is_pre31 = False
    try:
        if router.has_version('<', '3.1'):
            is_pre31 = True
            print("\nversion check failed, version < 3.1")
    except:
        is_pre31 = False

    if is_pre31 == True:
        print("\n\n** Skipping main tests on old version (<3.1)")
    else:
        print("\n\n** Running main test cases")
        print("******************************\n")

        luStart(os.path.dirname(os.path.realpath(__file__)), tgen.net)

        luInclude('teststart.py')
        # For debugging after starting FRR/Quagga daemons, uncomment the next line
        #CLI(net)

        luInclude('testfinish.py')
        print(luFinish())

        # For debugging after starting FRR/Quagga daemons, uncomment the next line
        #CLI(net)

        # Make sure that all daemons are running
        numFail = luNumFail()
        if numFail > 0:
            fatal_error = '%d tests failed' % numFail
            assert fatal_error == "", fatal_error

# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip('Memory leak test/report is disabled')

    tgen.report_memory_leaks()

if __name__ == '__main__':
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
