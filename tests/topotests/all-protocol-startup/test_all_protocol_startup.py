#!/usr/bin/env python

#
# test_all_protocol_startup.py
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
test_all_protocol_startup.py: Test of all protocols at same time

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
    "All Protocol Startup Test"

    def build(self, **_opts):

        # Setup Routers
        router = {}
        #
        # Setup Main Router
        router[1] = topotest.addRouter(self, 'r1')
        #

        # Setup Switches
        switch = {}
        #
        for i in range(0, 10):
            switch[i] = self.addSwitch('sw%s' % i, cls=topotest.LegacySwitch)
            self.addLink(switch[i], router[1], intfName2='r1-eth%s' % i )


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
    os.system('sudo rm /tmp/r* > /dev/null 2>&1')

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    if net['r1'].get_routertype() != 'frr':
        fatal_error = "Test is only implemented for FRR"
        sys.stderr.write('\n\nTest is only implemented for FRR - Skipping\n\n')
        pytest.skip(fatal_error)
        
    # Starting Routers
    #
    # Main router
    for i in range(1, 2):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ripd', '%s/r%s/ripd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ripngd', '%s/r%s/ripngd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospfd', '%s/r%s/ospfd.conf' % (thisDir, i))
        if net['r1'].checkRouterVersion('<', '4.0'):
            net['r%s' % i].loadConf('ospf6d', '%s/r%s/ospf6d.conf-pre-v4' % (thisDir, i))
	else:
	    net['r%s' % i].loadConf('ospf6d', '%s/r%s/ospf6d.conf' % (thisDir, i))
        net['r%s' % i].loadConf('isisd', '%s/r%s/isisd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('bgpd', '%s/r%s/bgpd.conf' % (thisDir, i))
        if net['r%s' % i].daemon_available('ldpd'):
            # Only test LDPd if it's installed and Kernel >= 4.5
            net['r%s' % i].loadConf('ldpd', '%s/r%s/ldpd.conf' % (thisDir, i))
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

    # Starting Routers
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_error_messages_vtysh():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check for error messages on VTYSH")
    print("******************************************\n")

    failures = 0
    for i in range(1, 2):
        #
        # First checking Standard Output
        #

        # VTYSH output from router
        vtystdout = net['r%s' % i].cmd('vtysh -c "show version" 2> /dev/null').rstrip()

        # Fix newlines (make them all the same)
        vtystdout = ('\n'.join(vtystdout.splitlines()) + '\n').rstrip()
        # Drop everything starting with "FRRouting X.xx" message
        vtystdout = re.sub(r"FRRouting [0-9]+.*", "", vtystdout, flags=re.DOTALL)

        if (vtystdout == ''):
            print("r%s StdOut ok" % i)

        assert vtystdout == '', "Vtysh StdOut Output check failed for router r%s" % i

        #
        # Second checking Standard Error
        #

        # VTYSH StdErr output from router
        vtystderr = net['r%s' % i].cmd('vtysh -c "show version" > /dev/null').rstrip()

        # Fix newlines (make them all the same)
        vtystderr = ('\n'.join(vtystderr.splitlines()) + '\n').rstrip()
        # # Drop everything starting with "FRRouting X.xx" message
        # vtystderr = re.sub(r"FRRouting [0-9]+.*", "", vtystderr, flags=re.DOTALL) 

        if (vtystderr == ''):
            print("r%s StdErr ok" % i)

        assert vtystderr == '', "Vtysh StdErr Output check failed for router r%s" % i

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_error_messages_daemons():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check for error messages in daemons")
    print("******************************************\n")

    error_logs = ""

    for i in range(1, 2):
        log = net['r%s' % i].getStdErr('ripd')
        if log:
            error_logs += "r%s RIPd StdErr Output:\n" % i
            error_logs += log
        log = net['r%s' % i].getStdErr('ripngd')
        if log:
            error_logs += "r%s RIPngd StdErr Output:\n" % i
            error_logs += log
        log = net['r%s' % i].getStdErr('ospfd')
        if log:
            error_logs += "r%s OSPFd StdErr Output:\n" % i
            error_logs += log
        log = net['r%s' % i].getStdErr('ospf6d')
        if log:
            error_logs += "r%s OSPF6d StdErr Output:\n" % i
            error_logs += log
        log = net['r%s' % i].getStdErr('isisd')
        # ISIS shows debugging enabled status on StdErr
        # Remove these messages
        log = re.sub(r"^IS-IS .* debugging is on.*", "", log).rstrip()
        if log:
            error_logs += "r%s ISISd StdErr Output:\n" % i
            error_logs += log
        log = net['r%s' % i].getStdErr('bgpd')
        if log:
            error_logs += "r%s BGPd StdErr Output:\n" % i
            error_logs += log
        if (net['r%s' % i].daemon_available('ldpd')): 
            log = net['r%s' % i].getStdErr('ldpd')
            if log:
                error_logs += "r%s LDPd StdErr Output:\n" % i
                error_logs += log
        log = net['r%s' % i].getStdErr('zebra')
        if log:
            error_logs += "r%s Zebra StdErr Output:\n"
            error_logs += log

    if error_logs:
        sys.stderr.write('Failed check for StdErr Output on daemons:\n%s\n' % error_logs)

    # Ignoring the issue if told to ignore (ie not yet fixed)
    if (error_logs != ""):
        if (os.environ.get('bamboo_TOPOTESTS_ISSUE_349') == "IGNORE"):
            sys.stderr.write('Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/349\n')
            pytest.skip('Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/349')

    assert error_logs == "", "Daemons report errors to StdErr"

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

    # Make sure that all daemons are running
    failures = 0
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

        print("Show that v4 routes are right\n");
        v4_routesFile = '%s/r%s/ipv4_routes.ref' % (thisDir, i)
        expected = open(v4_routesFile).read().rstrip()
        expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

        actual = net['r%s' %i].cmd('vtysh -c "show ip route" | /usr/bin/tail -n +7 | sort 2> /dev/null').rstrip()
        # Drop time in last update
        actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
        actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)
        diff = topotest.get_textdiff(actual, expected,
                                     title1="Actual IP Routing Table",
                                     title2="Expected IP RoutingTable")
        if diff:
            sys.stderr.write('r%s failed IP Routing table check:\n%s\n' % (i, diff))
            failures += 1
        else:
            print("r%s ok" %i)

        assert failures == 0, "IP Routing table failed for r%s\n%s" % (i, diff)

        failures = 0

        print("Show that v6 routes are right\n")
        v6_routesFile = '%s/r%s/ipv6_routes.ref' % (thisDir, i)
        expected = open(v6_routesFile).read().rstrip()
        expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

        actual = net['r%s' %i].cmd('vtysh -c "show ipv6 route" | /usr/bin/tail -n +7 | sort 2> /dev/null').rstrip()
        # Drop time in last update
        actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
        actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)
        diff = topotest.get_textdiff(actual, expected,
                                     title1="Actual IPv6 Routing Table",
                                     title2="Expected IPv6 RoutingTable")
        if diff:
            sys.stderr.write('r%s failed IPv6 Routing table check:\n%s\n' % (i, diff))
            failures += 1
        else:
            print("r%s ok" %i)

        assert failures == 0, "IPv6 Routing table failed for r%s\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    ## CLI(net)


def test_rip_status():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying RIP status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
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

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_ripng_status():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying RIPng status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/ripng_status.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ipv6 ripng status" 2> /dev/null').rstrip()
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Drop time in next due 
            actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
            # Drop time in last update
            actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual IPv6 RIPng status",
                title2="expected IPv6 RIPng status")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed IPv6 RIPng status check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IPv6 RIPng status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_ospfv2_interfaces():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying OSPFv2 interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/show_ip_ospf_interface.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip ospf interface" 2> /dev/null').rstrip()
            # Mask out Bandwidth portion. They may change..
            actual = re.sub(r"BW [0-9]+ Mbit", "BW XX Mbit", actual)
            # Drop time in next due 
            actual = re.sub(r"Hello due in [0-9\.]+s", "Hello due in XX.XXXs", actual)
            # Fix 'MTU mismatch detection: enabled' vs 'MTU mismatch detection:enabled' - accept both
            actual = re.sub(r"MTU mismatch detection:([a-z]+.*)", r"MTU mismatch detection: \1", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW IP OSPF INTERFACE",
                title2="expected SHOW IP OSPF INTERFACE")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW IP OSPF INTERFACE check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            # Ignoring the issue if told to ignore (ie not yet fixed)
            if (failures != 0):
                if (os.environ.get('bamboo_TOPOTESTS_ISSUE_348') == "IGNORE"):
                    sys.stderr.write('Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/348\n')
                    pytest.skip('Known issue - IGNORING. See https://github.com/FRRouting/frr/issues/348')

            assert failures == 0, "SHOW IP OSPF INTERFACE failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_isis_interfaces():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying ISIS interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/show_isis_interface_detail.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show isis interface detail" 2> /dev/null').rstrip()
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r"fe80::[0-9a-f:]+", "fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Mask out SNPA mac address portion. They are random...
            actual = re.sub(r"SNPA: [0-9a-f\.]+", "SNPA: XXXX.XXXX.XXXX", actual)
            # Mask out Circuit ID number
            actual = re.sub(r"Circuit Id: 0x[0-9]+", "Circuit Id: 0xXX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW ISIS INTERFACE DETAIL",
                title2="expected SHOW ISIS OSPF6 INTERFACE DETAIL")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW ISIS INTERFACE DETAIL check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW ISIS INTERFACE DETAIL failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_bgp_summary():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP Summary")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/show_ip_bgp_summary.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip bgp summary" 2> /dev/null').rstrip()
            # Mask out "using XXiXX bytes" portion. They are random...
            actual = re.sub(r"using [0-9]+ bytes", "using XXXX bytes", actual)
            # Mask out "using XiXXX KiB" portion. They are random...
            actual = re.sub(r"using [0-9]+ KiB", "using XXXX KiB", actual)
            #
            # Remove extra summaries which exist with newer versions
            #
            # Remove summary lines (changed recently)
            actual = re.sub(r'Total number.*', '', actual)
            actual = re.sub(r'Displayed.*', '', actual)
            # Remove IPv4 Unicast Summary (Title only)
            actual = re.sub(r'IPv4 Unicast Summary:', '', actual)
            # Remove IPv4 Multicast Summary (all of it)
            actual = re.sub(r'IPv4 Multicast Summary:', '', actual)
            actual = re.sub(r'No IPv4 Multicast neighbor is configured', '', actual)
            # Remove IPv4 VPN Summary (all of it)
            actual = re.sub(r'IPv4 VPN Summary:', '', actual)
            actual = re.sub(r'No IPv4 VPN neighbor is configured', '', actual)
            # Remove IPv4 Encap Summary (all of it)
            actual = re.sub(r'IPv4 Encap Summary:', '', actual)
            actual = re.sub(r'No IPv4 Encap neighbor is configured', '', actual)
            # Remove Unknown Summary (all of it)
            actual = re.sub(r'Unknown Summary:', '', actual)
            actual = re.sub(r'No Unknown neighbor is configured', '', actual)

            actual = re.sub(r'IPv4 labeled-unicast Summary:', '', actual)
            actual = re.sub(r'No IPv4 labeled-unicast neighbor is configured', '', actual)

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            #
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW IP BGP SUMMARY",
                title2="expected SHOW IP BGP SUMMARY")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW IP BGP SUMMARY check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IP BGP SUMMARY failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_bgp_ipv6_summary():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv6 Summary")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/show_bgp_ipv6_summary.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show bgp ipv6 summary" 2> /dev/null').rstrip()
            # Mask out "using XXiXX bytes" portion. They are random...
            actual = re.sub(r"using [0-9]+ bytes", "using XXXX bytes", actual)
            # Mask out "using XiXXX KiB" portion. They are random...
            actual = re.sub(r"using [0-9]+ KiB", "using XXXX KiB", actual)
            #
            # Remove extra summaries which exist with newer versions
            #
            # Remove summary lines (changed recently)
            actual = re.sub(r'Total number.*', '', actual)
            actual = re.sub(r'Displayed.*', '', actual)
            # Remove IPv4 Unicast Summary (Title only)
            actual = re.sub(r'IPv6 Unicast Summary:', '', actual)
            # Remove IPv4 Multicast Summary (all of it)
            actual = re.sub(r'IPv6 Multicast Summary:', '', actual)
            actual = re.sub(r'No IPv6 Multicast neighbor is configured', '', actual)
            # Remove IPv4 VPN Summary (all of it)
            actual = re.sub(r'IPv6 VPN Summary:', '', actual)
            actual = re.sub(r'No IPv6 VPN neighbor is configured', '', actual)
            # Remove IPv4 Encap Summary (all of it)
            actual = re.sub(r'IPv6 Encap Summary:', '', actual)
            actual = re.sub(r'No IPv6 Encap neighbor is configured', '', actual)
            # Remove Unknown Summary (all of it)
            actual = re.sub(r'Unknown Summary:', '', actual)
            actual = re.sub(r'No Unknown neighbor is configured', '', actual)

            # Remove Labeled Unicast Summary (all of it)
            actual = re.sub(r'IPv6 labeled-unicast Summary:', '', actual)
            actual = re.sub(r'No IPv6 labeled-unicast neighbor is configured', '', actual)

            # Strip empty lines
            actual = actual.lstrip()
            actual = actual.rstrip()
            #
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW BGP IPv6 SUMMARY",
                title2="expected SHOW BGP IPv6 SUMMARY")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW BGP IPv6 SUMMARY check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW BGP IPv6 SUMMARY failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_bgp_ipv4():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv4")
    print("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
	success = 0
	for refTableFile in (glob.glob(
		'%s/r%s/show_bgp_ipv4*.ref' % (thisDir, i))):
	    if os.path.isfile(refTableFile):
		# Read expected result from file
		expected = open(refTableFile).read().rstrip()
		# Fix newlines (make them all the same)
		expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

		# Actual output from router
		actual = net['r%s' % i].cmd('vtysh -c "show bgp ipv4" 2> /dev/null').rstrip()
		# Remove summary line (changed recently)
		actual = re.sub(r'Total number.*', '', actual)
		actual = re.sub(r'Displayed.*', '', actual)
		actual = actual.rstrip()
		# Fix newlines (make them all the same)
		actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

		# Generate Diff
		diff = topotest.get_textdiff(actual, expected,
		    title1="actual SHOW BGP IPv4",
		    title2="expected SHOW BGP IPv4")

		# Empty string if it matches, otherwise diff contains unified diff
		if diff:
		    diffresult[refTableFile] = diff
		else:
		    success = 1
		    print("template %s matched: r%s ok" % (refTableFile, i))
		    break

	if not success:
	    resultstr = 'No template matched.\n'
	    for f in diffresult.iterkeys():
		resultstr += (
		    'template %s: r%s failed SHOW BGP IPv4 check:\n%s\n'
		    % (f, i, diffresult[f]))
	    raise AssertionError(
		"SHOW BGP IPv4 failed for router r%s:\n%s" % (i, resultstr))

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_bgp_ipv6():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying BGP IPv6")
    print("******************************************\n")
    diffresult = {}
    for i in range(1, 2):
	success = 0
	for refTableFile in (glob.glob(
		'%s/r%s/show_bgp_ipv6*.ref' % (thisDir, i))):
	    if os.path.isfile(refTableFile):
		# Read expected result from file
		expected = open(refTableFile).read().rstrip()
		# Fix newlines (make them all the same)
		expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

		# Actual output from router
		actual = net['r%s' % i].cmd('vtysh -c "show bgp ipv6" 2> /dev/null').rstrip()
		# Remove summary line (changed recently)
		actual = re.sub(r'Total number.*', '', actual)
		actual = re.sub(r'Displayed.*', '', actual)
		actual = actual.rstrip()
		# Fix newlines (make them all the same)
		actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

		# Generate Diff
		diff = topotest.get_textdiff(actual, expected,
		    title1="actual SHOW BGP IPv6",
		    title2="expected SHOW BGP IPv6")

		# Empty string if it matches, otherwise diff contains unified diff
		if diff:
		    diffresult[refTableFile] = diff
		else:
		    success = 1
		    print("template %s matched: r%s ok" % (refTableFile, i))

	if not success:
	    resultstr = 'No template matched.\n'
	    for f in diffresult.iterkeys():
		resultstr += (
		    'template %s: r%s failed SHOW BGP IPv6 check:\n%s\n'
		    % (f, i, diffresult[f]))
	    raise AssertionError(
		"SHOW BGP IPv6 failed for router r%s:\n%s" % (i, resultstr))

    # Make sure that all daemons are running
    for i in range(1, 2):
        fatal_error = net['r%s' % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)



def test_mpls_interfaces():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Skip if no LDP installed or old kernel
    if (net['r1'].daemon_available('ldpd') == False):
        pytest.skip("No MPLS or kernel < 4.5")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying MPLS Interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        refTableFile = '%s/r%s/show_mpls_ldp_interface.ref' % (thisDir, i)
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

    print("\n\n** Verifying unexpected STDERR output from daemons")
    print("******************************************\n")

    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        print("SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n")
        pytest.skip('Skipping test for Stderr output')

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("thisDir=" + thisDir)

    net['r1'].stopRouter()

    log = net['r1'].getStdErr('ripd')
    if log:
        print("\nRIPd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('ripngd')
    if log:
        print("\nRIPngd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('ospfd')
    if log:
        print("\nOSPFd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('ospf6d')
    if log:
        print("\nOSPF6d StdErr Log:\n" + log)
    log = net['r1'].getStdErr('isisd')
    if log:
        print("\nISISd StdErr Log:\n" + log)
    log = net['r1'].getStdErr('bgpd')
    if log:
        print("\nBGPd StdErr Log:\n" + log)
    if (net['r1'].daemon_available('ldpd')):
        log = net['r1'].getStdErr('ldpd')
        if log:
            print("\nLDPd StdErr Log:\n" + log)
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

    for i in range(1, 2):
        net['r%s' % i].stopRouter()
        net['r%s' % i].report_memory_leaks(os.environ.get('TOPOTESTS_CHECK_MEMLEAK'), os.path.basename(__file__))


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
