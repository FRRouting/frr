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
test_ldp_topo1.py: Simple FRR/Quagga LDP Test

             +---------+
             |    r1   |
             | 1.1.1.1 |
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
             | 2.2.2.2 |
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
      |  3.3.3.3  |         | 4.4.4.4 |
      +-----------+         +---------+
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
from lib import topotest

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
    "LDP Test Topology 1"

    def build(self, **_opts):

        # Setup Routers
        router = {}
        for i in range(1, 5):
            router[i] = topotest.addRouter(self, 'r%s' % i)

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

    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    print("Cleanup old Mininet runs")
    os.system('sudo mn -c > /dev/null 2>&1')

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospfd', '%s/r%s/ospfd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ldpd', '%s/r%s/ldpd.conf' % (thisDir, i))
        fatal_error = net['r%s' % i].startRouter()

        if fatal_error != "":
            break

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
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR/Quagga is running on each Router node")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # Detect CLI Version
    # At this time, there are only 2 possible outputs, so simple check
    output = net['r1'].cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null').rstrip()

    # Check if old or new format of CLI Output. Default is to current format
    #
    # Old (v1) output looks like this:
    # Local LDP Identifier: 1.1.1.1:0
    # Discovery Sources:
    #   Interfaces:
    #     r1-eth0: xmit/recv
    #       LDP Id: 2.2.2.2:0, Transport address: 2.2.2.2
    #           Hold time: 15 sec
    #   Targeted Hellos:
    #
    # Current (v0) output looks like this:
    # AF   ID              Type     Source           Holdtime
    # ipv4 2.2.2.2         Link     r1-eth0                15
    pattern = re.compile("^Local LDP Identifier.*")
    if pattern.match(output):
        cli_version = "-1"

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)

def test_mpls_interfaces():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying MPLS Interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_interface.ref%s' % (thisDir, i, cli_version)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp interface" 2> /dev/null').rstrip()
            # Mask out Timer in Uptime
            actual = re.sub(r" [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ", " xx:xx:xx ", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual MPLS LDP interface status",
                title2="expected MPLS LDP interface status")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP Interface status Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            if failures>0:
                fatal_error = "MPLS LDP Interface status failed"

            assert failures == 0, "MPLS LDP Interface status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_ldp_neighbor_establish():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify MPLS LDP neighbors to establish")
    print("******************************************\n")
    timeout = 90
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 5):
            established = net['r%s' % i].cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null').rstrip()
            if cli_version != "-1":
                # On current version, we need to make sure they all turn to OPERATIONAL on all lines
                #
                lines = ('\n'.join(established.splitlines()) + '\n').splitlines(1)
                # Check all lines to be either table header (starting with ^AF or show OPERATIONAL)
                header = r'^AF.*'
                operational = r'^ip.*OPERATIONAL.*'
                found_operational = 0
                for j in range(1, len(lines)):
                    if (not re.search(header, lines[j])) and (not re.search(operational, lines[j])):
                        established = ""  # Empty string shows NOT established
                    if re.search(operational, lines[j]):
                        found_operational += 1
                if found_operational < 1:
                    # Need at least one operational neighbor
                    established = ""  # Empty string shows NOT established
            if not established:
                print('Waiting for r%s' %i)
                sys.stdout.flush()
                break
        if not established:
            sleep(5)
            timeout -= 5
        else:
            print('Done')
            break
    else:
        # Bail out with error if a router fails to converge
        fatal_error = "MPLS LDP neighbors did not establish"
        assert False, "MPLS LDP neighbors did not establish" % ospfStatus

    print("MPLS LDP neighbors established.")

    if timeout < 60:
        # Only wait if we actually went through a convergence
        print("\nwaiting 15s for LDP sessions to establish")
        sleep(15)
  
    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error


def test_mpls_ldp_discovery():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying MPLS LDP discovery")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_discovery.ref%s' % (thisDir, i, cli_version)
        if os.path.isfile(refTableFile):
            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null').rstrip()

            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null').rstrip()

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual MPLS LDP discovery output",
                title2="expected MPLS LDP discovery output")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP discovery output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface discovery output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_ldp_neighbor():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying MPLS LDP neighbor")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_neighbor.ref%s' % (thisDir, i, cli_version)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null').rstrip()

            # Mask out changing parts in output
            if cli_version == "-1":
                # Mask out Timer in Uptime
                actual = re.sub(r"Up time: [0-9][0-9]:[0-9][0-9]:[0-9][0-9]", "Up time: xx:xx:xx", actual)
                # Mask out Port numbers in TCP connection
                actual = re.sub(r"TCP connection: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]):[0-9]+ - ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]):[0-9]+",
                    r"TCP connection: \1:xxx - \2:xxx", actual)
            else:
                # Current Version
                #
                # Mask out Timer in Uptime
                actual = re.sub(r"(ipv4 [0-9\.]+ +OPERATIONAL [0-9\.]+ +)[0-9][0-9]:[0-9][0-9]:[0-9][0-9]", r"\1xx:xx:xx", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual MPLS LDP neighbor output",
                title2="expected MPLS LDP neighbor output")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP neighbor output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface neighbor output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)


def test_mpls_ldp_binding():
    global fatal_error
    global net
    global cli_version

    # Skip this test for now until proper sorting of the output
    # is implemented
    # pytest.skip("Skipping test_mpls_ldp_binding")

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying MPLS LDP binding")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_binding.ref%s' % (thisDir, i, cli_version)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp binding" 2> /dev/null').rstrip()

            # Mask out changing parts in output
            if cli_version == "-1":
                # Mask out label
                actual = re.sub(r"label: [0-9]+", "label: xxx", actual)
                actual = re.sub(r"(\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ ]+)[0-9]+", r"\1xxx", actual)
            else:
                # Current Version
                #
                # Mask out label
                actual = re.sub(r"(ipv4 [0-9\./]+ +[0-9\.]+ +)[0-9][0-9] (.*)", r"\1xxx\2", actual)
                actual = re.sub(r"(ipv4 [0-9\./]+ +[0-9\.]+ +[a-z\-]+ +)[0-9][0-9] (.*)", r"\1xxx\2", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Sort lines which start with "xx via inet "
            pattern = r'^\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+'
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual MPLS LDP binding output",
                title2="expected MPLS LDP binding output")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP binding output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface binding output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)


def test_zebra_ipv4_routingTable():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_ipv4_route.ref%s' % (thisDir, i, cli_version)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip route" 2> /dev/null | grep "^O"').rstrip()
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)

            # Mask out label - all LDP labels should be >= 10 (2-digit)
            #   leaving the implicit labels unmasked
            actual = re.sub(r" label [0-9][0-9]+", " label xxx", actual)
            #   and translating remaining implicit (single-digit) labels to label implicit-null
            actual = re.sub(r" label [0-9]+", " label implicit-null", actual)
            # Check if we have implicit labels - if not, then remove them from reference
            if (not re.search(r" label implicit-null", actual)):
                expected = re.sub(r", label implicit-null", "", expected)

            # now fix newlines of expected (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Add missing comma before label (for old version)
            actual = re.sub(r"([0-9]) label ", r"\1, label ", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual IPv4 zebra routing table",
                title2="expected IPv4 zebra routing table")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed IPv4 Zebra Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IPv4 Zebra Routing Table verification failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_table():
    global fatal_error
    global net
    global cli_version

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying MPLS table")
    print("******************************************\n")
    failures = 0

    version = cli_version
    if (version == ""):
        # check for new output without implicit-null
        output = net['r1'].cmd('vtysh -c "show mpls table" 2> /dev/null').rstrip()
        if 'LDP         10.0.1.2         3' in output:
            version = "-no-impl-null"

    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_table.ref%s' % (thisDir, i, version)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls table" 2> /dev/null').rstrip()
 
            # Fix inconsistent Label numbers at beginning of line
            actual = re.sub(r"(\s+)[0-9]+(\s+LDP)", r"\1XX\2", actual)
            # Fix inconsistent Label numbers at end of line
            actual = re.sub(r"(\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+)[0-9][0-9]", r"\1XX", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Sort lines which start with "      XX      LDP"
            pattern = r'^\s+[0-9X]+\s+LDP'
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual MPLS table output",
                title2="expected MPLS table output")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS table output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS table output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_linux_mpls_routes():
    global fatal_error
    global net
    global cli_version

   # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying Linux Kernel MPLS routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/ip_mpls_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('ip -o -family mpls route 2> /dev/null').rstrip()

            # Mask out label and protocol
            actual = re.sub(r"[0-9][0-9] via inet ", "xx via inet ", actual)
            actual = re.sub(r"[0-9][0-9] +proto", "xx  proto", actual)
            actual = re.sub(r"[0-9][0-9] as to ", "xx as to ", actual)
            actual = re.sub(r"[ ]+proto \w+", "  proto xx", actual)

            # Sort nexthops
            nexthop_sorted = []
            for line in actual.splitlines():
                tokens = re.split(r'\\\t', line.strip())
                nexthop_sorted.append('{} {}'.format(
                    tokens[0].strip(),
                    ' '.join([ token.strip() for token in sorted(tokens[1:]) ])
                ).strip())

            # Sort lines and fixup differences between old and new iproute
            actual = '\n'.join(sorted(nexthop_sorted))
            actual = re.sub(r"nexthop via", "nexthopvia", actual)
            actual = re.sub(r" nexthop as to xx via inet ", " nexthopvia inet ", actual)
            actual = re.sub(r" weight 1", "", actual)
            actual = re.sub(r" [ ]+", " ", actual)

            # put \n back at line ends
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual Linux Kernel MPLS route",
                title2="expected Linux Kernel MPLS route")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed Linux Kernel MPLS route output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Linux Kernel MPLS route output for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 5):
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

    for i in range(1, 5):
        net['r%s' % i].stopRouter()
        log = net['r%s' % i].getStdErr('ldpd')
        if log:
            print("\nRouter r%s LDPd StdErr Log:\n%s" % (i, log))
        log = net['r%s' % i].getStdErr('ospfd')
        if log:
            print("\nRouter r%s OSPFd StdErr Log:\n%s" % (i, log))
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
