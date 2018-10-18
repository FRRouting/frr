#!/usr/bin/env python

#
# test_ospf6_topo1.py
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
test_ospf6_topo1.py:

                                                  -----\
  SW1 - Stub Net 1            SW2 - Stub Net 2          \
  fc00:1:1:1::/64             fc00:2:2:2::/64            \
\___________________/      \___________________/          |
          |                          |                    |
          |                          |                    |
          | ::1                      | ::2                |
+---------+---------+      +---------+---------+          |
|        R1         |      |        R2         |          |
|     FRRouting     |      |     FRRouting     |          |
| Rtr-ID: 10.0.0.1  |      | Rtr-ID: 10.0.0.2  |          |
+---------+---------+      +---------+---------+          |
          | ::1                      | ::2                 \
           \______        ___________/                      OSPFv3
                  \      /                               Area 0.0.0.0
                   \    /                                  /
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW5        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:A:A:A::/64 ~~                         |
             ~~~~~~~~~~~~~~~~~~                           |
                     |                 /----              |
                     | ::3            | SW3 - Stub Net 3  | 
           +---------+---------+    /-+ fc00:3:3:3::/64   |
           |        R3         |   /  |                  /
           |     FRRouting     +--/    \----            /
           | Rtr-ID: 10.0.0.3  | ::3        ___________/
           +---------+---------+                       \
                     | ::3                              \
                     |                                   \
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW6        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:B:B:B::/64 ~~                          \
             ~~~~~~~~~~~~~~~~~~                             OSPFv3
                     |                                   Area 0.0.0.1
                     | ::4                                 /
           +---------+---------+       /----              |
           |        R4         |      | SW4 - Stub Net 4  |
           |     FRRouting     +------+ fc00:4:4:4::/64   |
           | Rtr-ID: 10.0.0.4  | ::4  |                   /
           +-------------------+       \----             /
                                                   -----/
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
    "OSPFv3 (IPv6) Test Topology 1"

    def build(self, **_opts):
        #
        # Define Switches first
        #
        switch = {}
        for i in range(1, 7):
            switch[i] = self.addSwitch('SW%s' % i, 
                                       dpid=topotest.int2dpid(i),
                                       cls=topotest.LegacySwitch)
        #
        # Define FRR/Quagga Routers
        #
        router = {}
        for i in range(1, 5):
            router[i] = topotest.addRouter(self, 'r%s' % i)

        #
        # Wire up the switches and routers
        #
        # Stub nets
        for i in range(1, 5):
            self.addLink(switch[i], router[i], intfName2='r%s-stubnet' % i)
        # Switch 5
        self.addLink(switch[5], router[1], intfName2='r1-sw5')
        self.addLink(switch[5], router[2], intfName2='r2-sw5')
        self.addLink(switch[5], router[3], intfName2='r3-sw5')
        # Switch 6
        self.addLink(switch[6], router[3], intfName2='r3-sw6')
        self.addLink(switch[6], router[4], intfName2='r4-sw6')


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

    # For debugging after starting net, but before starting FRR/Quagga, uncomment the next line
    # CLI(net)

    ospf_config = 'ospf6d.conf'
    if net['r1'].checkRouterVersion('<', '4.0'):
        ospf_config = 'ospf6d.conf-pre-v4'

    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospf6d', '%s/r%s/%s' % (thisDir, i, ospf_config))
        net['r%s' % i].startRouter()

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
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
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)

def test_ospf6_converged():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify OSPF6 daemons to converge")
    print("******************************************\n")
    timeout = 60
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 5):
            notConverged = net['r%s' % i].cmd('vtysh -c "show ipv6 ospf neigh" 2> /dev/null | grep ^[0-9] | grep -v Full')
            if notConverged:
                print('Waiting for r%s' %i)
                sys.stdout.flush()
                break
        if notConverged:
            sleep(5)
            timeout -= 5
        else:
            print('Done')
            print(notConverged)
            break
    else:
        # Bail out with error if a router fails to converge
        ospfStatus = net['r%s' % i].cmd('vtysh -c "show ipv6 ospf neigh"')
        fatal_error = "OSPFv6 did not converge"
        assert False, "OSPFv6 did not converge:\n%s" % ospfStatus

    print("OSPFv3 converged.")

    if timeout < 60:
        # Only wait if we actually went through a convergence
        print("\nwaiting 15s for routes to populate")
        sleep(15)

    # Make sure that all daemons are still running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

def test_ospfv3_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying OSPFv3 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_ipv6_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ipv6 route" 2> /dev/null | grep "^O"').rstrip()
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual OSPFv3 IPv6 routing table",
                title2="expected OSPFv3 IPv6 routing table")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed OSPFv3 (IPv6) Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "OSPFv3 (IPv6) Routing Table verification failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)

def test_linux_ipv6_kernel_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify Linux Kernel Routing Table
    print("\n\n** Verifying Linux IPv6 Kernel Routing Table")
    print("******************************************\n")
    failures = 0

    # Get a list of all current link-local addresses first as they change for
    # each run and we need to translate them
    linklocals = []
    for i in range(1, 5):
        linklocals += net['r%s' % i].get_ipv6_linklocal()

    # Now compare the routing tables (after substituting link-local addresses)        
    for i in range(1, 5):
        refTableFile = '%s/r%s/ip_6_address.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):

            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines())).splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('ip -6 route').rstrip()
            # Mask out Link-Local mac addresses
            for ll in linklocals:
                actual = actual.replace(ll[1], "fe80::__(%s)__" % ll[0])
            # Mask out protocol name or number
            actual = re.sub(r"[ ]+proto [0-9a-z]+ +", "  proto XXXX ", actual)
            # Remove ff00::/8 routes (seen on some kernels - not from FRR)
            actual = re.sub(r'ff00::/8.*', '', actual)

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            actual = re.sub(r'  +', ' ', actual)

            filtered_lines = []
            for line in sorted(actual.splitlines()):
                if line.startswith('fe80::/64 ') \
                        or line.startswith('unreachable fe80::/64 '):
                    continue
                filtered_lines.append(line)
            actual = '\n'.join(filtered_lines).splitlines(1)

            # Print Actual table
            # print("Router r%s table" % i)
            # for line in actual:
            #     print(line.rstrip())

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual OSPFv3 IPv6 routing table",
                title2="expected OSPFv3 IPv6 routing table")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed Linux IPv6 Kernel Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Linux Kernel IPv6 Routing Table verification failed for router r%s:\n%s" % (i, diff)

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

    for i in range(1, 5):
        net['r%s' % i].stopRouter()
        log = net['r%s' % i].getStdErr('ospf6d')
        if log:
            print("\nRouter r%s OSPF6d StdErr Log:\n%s" % (i, log))
        log = net['r%s' % i].getStdErr('zebra')
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


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
