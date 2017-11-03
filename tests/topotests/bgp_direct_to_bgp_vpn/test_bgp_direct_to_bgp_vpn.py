#!/usr/bin/env python

#
# test_bgp_multiview_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2016 by
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
import re
import sys
import pytest
from time import sleep

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/utilities')

from lib import topotest

from lutil import luStart, luInclude, luFinish, luNumFail

fatal_error = ""

# Expected version of CLI Output - Appendix to filename
#  empty string = current, latest output (default)
#  "-1" ... "-NNN" previous versions (incrementing with each version)
cli_version = ""

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "VPN Test Topology 1"

    def build(self, **_opts):

        # Setup Routers
        router = {}
        for i in range(1, 5):
            router[i] = topotest.addRouter(self, 'r%s' % i)
        ce = {}
        for i in range(1, 4):
            ce[i] = topotest.addRouter(self, 'ce%s' % i)

        self.addLink(ce[1], router[1], intfName1='ce1-eth0', intfName2='r1-eth4', addr1='00:11:01:00:00:00', addr2='00:11:00:01:00:04')
        self.addLink(ce[2], router[3], intfName1='ce2-eth0', intfName2='r3-eth4', addr1='00:11:02:00:00:00', addr2='00:11:00:03:00:04')
        self.addLink(ce[3], router[4], intfName1='ce3-eth0', intfName2='r4-eth4', addr1='00:11:03:00:00:00', addr2='00:11:00:04:00:04')
        # Setup Switches, add Interfaces and Connections
        switch = {}
        # First switch
        switch[0] = self.addSwitch('sw0', cls=topotest.LegacySwitch)
        self.addLink(switch[0], router[1], intfName2='r1-eth0', addr1='80:AA:00:00:00:00', addr2='00:11:00:01:00:00')
        self.addLink(switch[0], router[2], intfName2='r2-eth0', addr1='80:AA:00:00:00:01', addr2='00:11:00:02:00:00')
        # Second switch
        switch[1] = self.addSwitch('sw1', cls=topotest.LegacySwitch)
        self.addLink(switch[1], router[2], intfName2='r2-eth1', addr1='80:AA:00:01:00:00', addr2='00:11:00:02:00:01')
        self.addLink(switch[1], router[3], intfName2='r3-eth0', addr1='80:AA:00:01:00:01', addr2='00:11:00:03:00:00')
        self.addLink(switch[1], router[4], intfName2='r4-eth0', addr1='80:AA:00:01:00:02', addr2='00:11:00:04:00:00')
        # Third switch
        switch[2] = self.addSwitch('sw2', cls=topotest.LegacySwitch)
        self.addLink(switch[2], router[2], intfName2='r2-eth2', addr1='80:AA:00:02:00:00', addr2='00:11:00:02:00:02')
        self.addLink(switch[2], router[3], intfName2='r3-eth1', addr1='80:AA:00:02:00:01', addr2='00:11:00:03:00:01')

#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    global topo, net
    global fatal_error
    global thisDir

    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    print("Cleanup old Mininet runs")
    os.system('sudo mn -c > /dev/null 2>&1')

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()
    luStart(thisDir, net)
    
    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospfd', '%s/r%s/ospfd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ldpd', '%s/r%s/ldpd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('bgpd', '%s/r%s/bgpd.conf' % (thisDir, i))
        fatal_error = net['r%s' % i].startRouter()

        if fatal_error != "":
            break

    # Starting CE Routers
    for i in range(1, 4):
        net['ce%s' % i].loadConf('zebra', '%s/ce%s/zebra.conf' % (thisDir, i))
        net['ce%s' % i].loadConf('bgpd', '%s/ce%s/bgpd.conf' % (thisDir, i))
        fatal_error = net['ce%s' % i].startRouter()

        if fatal_error != "":
            break

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)

def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    # End - Shutdown network
    net.stop()

def test_add_vnc_routes():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Running main test cases")
    print("******************************\n")
    luInclude('teststart.py')
    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)

    luInclude('testfinish.py')
    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)

    # Make sure that all daemons are running
    numFail = luNumFail()
    if numFail > 0:
        fatal_error = '%d tests failed' % numFail
        assert fatal_error == "", fatal_error

def test_shutdown_check_stderr():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        print("SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n")
        pytest.skip('Skipping test for Stderr output')

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying unexpected STDERR output from daemons")
    print("******************************************\n")

    for i in range(1, 5):
        net['r%s' % i].stopRouter()
        log = net['r%s' % i].getStdErr('bgpd')
        if log:
            print("\nRouter r%s BGPd StdErr Log:\n%s" % (i, log))
        log = net['r%s' % i].getStdErr('ldpd')
        if log:
            print("\nRouter r%s LDPd StdErr Log:\n%s" % (i, log))
        log = net['r%s' % i].getStdErr('ospfd')
        if log:
            print("\nRouter r%s OSPFd StdErr Log:\n%s" % (i, log))
        log = net['r%s' % i].getStdErr('zebra')
        if log:
            print("\nRouter r%s Zebra StdErr Log:\n%s" % (i, log))

    for i in range(1, 4):
        net['ce%s' % i].stopRouter()
        log = net['ce%s' % i].getStdErr('bgpd')
        if log:
            print("\nRouter r%s BGPd StdErr Log:\n%s" % (i, log))
        log = net['ce%s' % i].getStdErr('zebra')
        if log:
            print("\nRouter r%s Zebra StdErr Log:\n%s" % (i, log))


def test_shutdown_check_memleak():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    if os.environ.get('TOPOTESTS_CHECK_MEMLEAK') is None:
        print("SKIPPED final check on Memory leaks: Disabled (TOPOTESTS_CHECK_MEMLEAK undefined)\n")
        pytest.skip('Skipping test for memory leaks')
    
    thisDir = os.path.dirname(os.path.realpath(__file__))

    for i in range(1, 5):
        net['r%s' % i].stopRouter()
        net['r%s' % i].report_memory_leaks(os.environ.get('TOPOTESTS_CHECK_MEMLEAK'), os.path.basename(__file__))

    for i in range(1, 4):
        net['ce%s' % i].stopRouter()
        net['ce%s' % i].report_memory_leaks(os.environ.get('TOPOTESTS_CHECK_MEMLEAK'), os.path.basename(__file__))

if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    print(luFinish())
    sys.exit(retval)
