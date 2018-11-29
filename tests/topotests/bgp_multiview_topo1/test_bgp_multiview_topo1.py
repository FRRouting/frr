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
test_bgp_multiview_topo1.py: Simple Quagga/FRR Route-Server Test

+----------+ +----------+ +----------+ +----------+ +----------+
|  peer1   | |  peer2   | |  peer3   | |  peer4   | |  peer5   |
| AS 65001 | | AS 65002 | | AS 65003 | | AS 65004 | | AS 65005 |
+-----+----+ +-----+----+ +-----+----+ +-----+----+ +-----+----+
      | .1         | .2         | .3         | .4         | .5 
      |     ______/            /            /   _________/
       \   /  ________________/            /   /     
        | |  /   _________________________/   /     +----------+  
        | | |  /   __________________________/   ___|  peer6   |
        | | | |  /  ____________________________/.6 | AS 65006 |
        | | | | |  /  _________________________     +----------+
        | | | | | |  /  __________________     \    +----------+ 
        | | | | | | |  /                  \     \___|  peer7   |
        | | | | | | | |                    \     .7 | AS 65007 |
     ~~~~~~~~~~~~~~~~~~~~~                  \       +----------+
   ~~         SW1         ~~                 \      +----------+
   ~~       Switch           ~~               \_____|  peer8   |  
   ~~    172.16.1.0/24     ~~                    .8 | AS 65008 |
     ~~~~~~~~~~~~~~~~~~~~~                          +----------+
              |
              | .254
    +---------+---------+
    |      FRR R1       |
    |   BGP Multi-View  |
    | Peer 1-3 > View 1 |       
    | Peer 4-5 > View 2 |
    | Peer 6-8 > View 3 |
    +---------+---------+
              | .1
              |
        ~~~~~~~~~~~~~        Stub Network is redistributed
      ~~     SW0     ~~      into each BGP view with different
    ~~   172.20.0.1/28  ~~   attributes (using route-map)
      ~~ Stub Switch ~~
        ~~~~~~~~~~~~~
"""  

import os
import re
import sys
import pytest
import glob
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


#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "BGP Multiview Topology 1"

    def build(self, **_opts):

        exabgpPrivateDirs = ['/etc/exabgp',
                             '/var/run/exabgp',
                             '/var/log']

        # Setup Routers
        router = {}
        for i in range(1, 2):
            router[i] = topotest.addRouter(self, 'r%s' % i)

        # Setup Provider BGP peers
        peer = {}
        for i in range(1, 9):
            peer[i] = self.addHost('peer%s' % i, ip='172.16.1.%s/24' % i,
                                    defaultRoute='via 172.16.1.254',
                                    privateDirs=exabgpPrivateDirs)

        # Setup Switches
        switch = {}
        # First switch is for a dummy interface (for local network)
        switch[0] = self.addSwitch('sw0', cls=topotest.LegacySwitch)
        self.addLink(switch[0], router[1], intfName2='r1-stub')
        # Second switch is for connection to all peering routers
        switch[1] = self.addSwitch('sw1', cls=topotest.LegacySwitch)
        self.addLink(switch[1], router[1], intfName2='r1-eth0')
        for j in range(1, 9):
            self.addLink(switch[1], peer[j], intfName2='peer%s-eth0' % j)


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

    # Starting PE Hosts and init ExaBGP on each of them
    print('*** Starting BGP on all 8 Peers in 10s')
    sleep(10)
    for i in range(1, 9):
        net['peer%s' % i].cmd('cp %s/exabgp.env /etc/exabgp/exabgp.env' % thisDir)
        net['peer%s' % i].cmd('cp %s/peer%s/* /etc/exabgp/' % (thisDir, i))
        net['peer%s' % i].cmd('chmod 644 /etc/exabgp/*')
        net['peer%s' % i].cmd('chmod 755 /etc/exabgp/*.py')
        net['peer%s' % i].cmd('chown -R exabgp:exabgp /etc/exabgp')
        net['peer%s' % i].cmd('exabgp -e /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg')
        print('peer%s' % i),
    print('')

    # For debugging after starting Quagga/FRR daemons, uncomment the next line
    # CLI(net)

def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    # Shutdown - clean up everything
    print('*** Killing BGP on Peer routers')
    # Killing ExaBGP
    for i in range(1, 9):
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


def test_bgp_converge():
    "Check for BGP converged on all peers and BGP views"

    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Wait for BGP to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify for BGP to converge")
    print("******************************************\n")
    timeout = 60
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 2):
            for view in range(1, 4):
                notConverged = net['r%s' % i].cmd('vtysh -c "show ip bgp view %s summary" 2> /dev/null | grep ^[0-9] | grep -v " 11$"' % view)
                if notConverged:
                    print('Waiting for r%s, view %s' % (i, view))
                    sys.stdout.flush()
                    break
            if notConverged:
                break
        if notConverged:
            sleep(5)
            timeout -= 5
        else:
            print('Done')
            break
    else:
        # Bail out with error if a router fails to converge
        bgpStatus = net['r%s' % i].cmd('vtysh -c "show ip bgp view %s summary"' % view)
        assert False, "BGP did not converge:\n%s" % bgpStatus

    # Wait for an extra 30s to announce all routes
    print('Waiting 30s for routes to be announced');
    sleep(30)
    
    print("BGP converged.")

    # if timeout < 60:
    #     # Only wait if we actually went through a convergence
    #     print("\nwaiting 15s for routes to populate")
    #     sleep(15)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting Quagga/FRR daemons, uncomment the next line
    # CLI(net)

def test_bgp_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP Routing Tables")
    print("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
        for view in range(1, 4):
            success = 0
            # This glob pattern should work as long as number of views < 10
            for refTableFile in (glob.glob(
                '%s/r%s/show_ip_bgp_view_%s*.ref' % (thisDir, i, view))):

                if os.path.isfile(refTableFile):
                    # Read expected result from file
                    expected = open(refTableFile).read().rstrip()
                    # Fix newlines (make them all the same)
                    expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

                    # Actual output from router
                    actual = net['r%s' % i].cmd('vtysh -c "show ip bgp view %s" 2> /dev/null' % view).rstrip()
        
                    # Fix inconsitent spaces between 0.99.24 and newer versions of Quagga...
                    actual = re.sub('0             0', '0              0', actual)
                    actual = re.sub(r'([0-9])         32768', r'\1          32768', actual)
                    # Remove summary line (changed recently)
                    actual = re.sub(r'Total number.*', '', actual)
                    actual = re.sub(r'Displayed.*', '', actual)
                    actual = actual.rstrip()
                    # Fix table version (ignore it)
                    actual = re.sub(r'(BGP table version is )[0-9]+', r'\1XXX', actual)

                    # Fix newlines (make them all the same)
                    actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

                # Generate Diff
                diff = topotest.get_textdiff(actual, expected,
                    title1="actual BGP routing table",
                    title2="expected BGP routing table")

                if diff:
                    diffresult[refTableFile] = diff
                else:
                    success = 1
                    print("template %s matched: r%s ok" % (refTableFile, i))
                    break;

            if not success:
                resultstr = 'No template matched.\n'
                for f in diffresult.iterkeys():
                    resultstr += (
                        'template %s: r%s failed Routing Table Check for view %s:\n%s\n'
                        % (f, i, view, diffresult[f]))
                raise AssertionError(
                    "Routing Table verification failed for router r%s, view %s:\n%s" % (i, view, resultstr))


    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


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

    net['r1'].stopRouter()

    log = net['r1'].getStdErr('bgpd')
    if log:
        print("\nBGPd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('zebra')
    if log:
        print("\nZebra StdErr Log:\n" + log)


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

    net['r1'].stopRouter()
    net['r1'].report_memory_leaks(os.environ.get('TOPOTESTS_CHECK_MEMLEAK'), os.path.basename(__file__))


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
