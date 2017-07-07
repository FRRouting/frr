#!/usr/bin/env python

#
# test_bgp_ecmp_topo1.py
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
test_bgp_ecmp_topo1.py: Test BGP topology with ECMP (Equal Cost MultiPath).
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

from functools import partial

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest

fatal_error = ""

total_ebgp_peers = 20

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "BGP ECMP Topology 1"

    def build(self, **_opts):

        exabgpPrivateDirs = ['/etc/exabgp',
                             '/var/run/exabgp',
                             '/var/log']

        # Setup Router
        router = {}
        router[1] = topotest.addRouter(self, 'r1')

        # Setup Switches - 1 switch per 5 peering routers
        switch = {}
        for swNum in range(1, (total_ebgp_peers+4)/5 +1):
            print("Create switch s%d", swNum)
            switch[swNum] = self.addSwitch('s%d' % (swNum), cls=topotest.LegacySwitch)
            self.addLink(switch[swNum], router[1], intfName2='r1-eth%d' % (swNum-1))

        # Add 'total_ebgp_peers' number of eBGP ExaBGP neighbors
        peer = {}
        for peerNum in range(1, total_ebgp_peers+1):
            swNum = ((peerNum -1) / 5 + 1)

            peer[peerNum] = self.addHost('peer%s' % peerNum, ip='10.0.%s.%s/24' % (swNum, (peerNum+100)),
                                    defaultRoute='via 10.0.%s.1' % swNum,
                                    privateDirs=exabgpPrivateDirs)
            self.addLink(switch[swNum], peer[peerNum], intfName2='peer%s-eth0' % peerNum)


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    global topo, net

    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    print("Cleanup old Mininet runs")
    os.system('sudo mn -c > /dev/null 2>&1')

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    # Starting Routers
    for i in range(1, 2):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('bgpd', '%s/r%s/bgpd.conf' % (thisDir, i))
        net['r%s' % i].startRouter()

    # Starting Hosts and init ExaBGP on each of them
    print('*** Starting BGP on all %d Peers in 10s' % total_ebgp_peers)
    sleep(10)
    for i in range(1, total_ebgp_peers+1):
        net['peer%s' % i].cmd('cp %s/exabgp.env /etc/exabgp/exabgp.env' % thisDir)
        net['peer%s' % i].cmd('cp %s/peer%s/* /etc/exabgp/' % (thisDir, i))
        net['peer%s' % i].cmd('chmod 644 /etc/exabgp/*')
        net['peer%s' % i].cmd('chmod 755 /etc/exabgp/*.py')
        net['peer%s' % i].cmd('chown -R exabgp:exabgp /etc/exabgp')
        net['peer%s' % i].cmd('exabgp -e /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg')
        print('peer%s' % i),
    print('')

    # For debugging after starting Quagga/FRR daemons, uncomment the next line
    CLI(net)


def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    # Shutdown - clean up everything
    print('*** Killing BGP on Peer routers')
    # Killing ExaBGP
    for i in range(1, total_ebgp_peers+1):
        net['peer%s' % i].cmd('kill `cat /var/run/exabgp/exabgp.pid`')

    # End - Shutdown network
    net.stop()


def test_router_running():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR/Quagga is running on each Router node")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
