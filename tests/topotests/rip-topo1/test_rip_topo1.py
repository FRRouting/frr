#!/usr/bin/env python

#
# test_rip_topo1.py
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
test_rip_topo1.py: Testing RIPv2

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


#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "RIP Topology 1"

    def build(self, **_opts):

        # Setup Routers
        router = {}
        #
        # Setup Main Router
        router[1] = topotest.addRouter(self, 'r1')
        #
        # Setup RIP Routers
        for i in range(2, 4):
            router[i] = topotest.addRouter(self, 'r%s' % i)
        #
        # Setup Switches
        switch = {}
        #
        # On main router
        # First switch is for a dummy interface (for local network)
        switch[1] = self.addSwitch('sw1', cls=topotest.LegacySwitch)
        self.addLink(switch[1], router[1], intfName2='r1-eth0')
        #
        # Switches for RIP
        # switch 2 switch is for connection to RIP router
        switch[2] = self.addSwitch('sw2', cls=topotest.LegacySwitch)
        self.addLink(switch[2], router[1], intfName2='r1-eth1')
        self.addLink(switch[2], router[2], intfName2='r2-eth0')
        # switch 3 is between RIP routers
        switch[3] = self.addSwitch('sw3', cls=topotest.LegacySwitch)
        self.addLink(switch[3], router[2], intfName2='r2-eth1')
        self.addLink(switch[3], router[3], intfName2='r3-eth1')
        # switch 4 is stub on remote RIP router
        switch[4] = self.addSwitch('sw4', cls=topotest.LegacySwitch)
        self.addLink(switch[4], router[3], intfName2='r3-eth0')



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
    #
    for i in range(1, 4):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ripd', '%s/r%s/ripd.conf' % (thisDir, i))
        net['r%s' % i].startRouter()

    # For debugging after starting Quagga/FRR daemons, uncomment the next line
    # CLI(net)


def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

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

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_converge_protocols():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 60 secs for now
    sleep(60)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_rip_status():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/rip_status.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip rip status" 2> /dev/null').rstrip()
            # Drop time in next due 
            actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
            # Drop time in last update
            actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual IP RIP status",
                title2="expected IP RIP status")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed IP RIP status check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IP RIP status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_rip_routes():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/show_ip_rip.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip rip" 2> /dev/null').rstrip()
            # Drop Time
            actual = re.sub(r"[0-9][0-9]:[0-5][0-9]", "XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW IP RIP",
                title2="expected SHOW IP RIP")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW IP RIP check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IP RIP failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_zebra_ipv4_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/show_ip_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip route" 2> /dev/null | grep "^R"').rstrip()
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual Zebra IPv4 routing table",
                title2="expected Zebra IPv4 routing table")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed Zebra IPv4 Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Zebra IPv4 Routing Table verification failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
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
        pytest.skip('Skipping test for Stderr output and memory leaks')

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifing unexpected STDERR output from daemons")
    print("******************************************\n")

    net['r1'].stopRouter()

    log = net['r1'].getStdErr('ripd')
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('zebra')
    if log:
        print("\nZebra StdErr Log:\n" + log)


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
