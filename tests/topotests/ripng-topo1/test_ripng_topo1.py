#!/usr/bin/env python

#
# test_ripng_topo1.py
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
test_ripng_topo1.py: Test of RIPng Topology

"""

import os
import re
import sys
import pytest
import unicodedata
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
    "RIPng Topology 1"

    def build(self, **_opts):

        # Setup Routers
        router = {}
        #
        # Setup Main Router
        router[1] = topotest.addRouter(self, "r1")
        #
        # Setup RIPng Routers
        for i in range(2, 4):
            router[i] = topotest.addRouter(self, "r%s" % i)

        # Setup Switches
        switch = {}
        #
        # On main router
        # First switch is for a dummy interface (for local network)
        switch[1] = self.addSwitch("sw1", cls=topotest.LegacySwitch)
        self.addLink(switch[1], router[1], intfName2="r1-eth0")
        #
        # Switches for RIPng
        # switch 2 switch is for connection to RIP router
        switch[2] = self.addSwitch("sw2", cls=topotest.LegacySwitch)
        self.addLink(switch[2], router[1], intfName2="r1-eth1")
        self.addLink(switch[2], router[2], intfName2="r2-eth0")
        # switch 3 is between RIP routers
        switch[3] = self.addSwitch("sw3", cls=topotest.LegacySwitch)
        self.addLink(switch[3], router[2], intfName2="r2-eth1")
        self.addLink(switch[3], router[3], intfName2="r3-eth1")
        # switch 4 is stub on remote RIP router
        switch[4] = self.addSwitch("sw4", cls=topotest.LegacySwitch)
        self.addLink(switch[4], router[3], intfName2="r3-eth0")

        switch[5] = self.addSwitch("sw5", cls=topotest.LegacySwitch)
        self.addLink(switch[5], router[1], intfName2="r1-eth2")
        switch[6] = self.addSwitch("sw6", cls=topotest.LegacySwitch)
        self.addLink(switch[6], router[1], intfName2="r1-eth3")


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
    os.system("sudo mn -c > /dev/null 2>&1")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    # Starting Routers
    #
    for i in range(1, 4):
        net["r%s" % i].loadConf("zebra", "%s/r%s/zebra.conf" % (thisDir, i))
        net["r%s" % i].loadConf("ripngd", "%s/r%s/ripngd.conf" % (thisDir, i))
        net["r%s" % i].startRouter()

    # For debugging after starting FRR daemons, uncomment the next line
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
    if fatal_error != "":
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR is running on each Router node")
    print("******************************************\n")

    # Starting Routers
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # CLI(net)


def test_converge_protocols():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 11 secs for now
    sleep(11)

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # CLI(net)


def test_ripng_status():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifying RIPng status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/ripng_status.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ipv6 ripng status" 2> /dev/null')
                .rstrip()
            )
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Drop time in next due
            actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
            # Drop time in last update
            actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual IPv6 RIPng status",
                title2="expected IPv6 RIPng status",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed IPv6 RIPng status check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IPv6 RIPng status failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # CLI(net)


def test_ripng_routes():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIPng Status
    print("\n\n** Verifying RIPng routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ipv6_ripng.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i].cmd('vtysh -c "show ipv6 ripng" 2> /dev/null').rstrip()
            )
            # Drop Time
            actual = re.sub(r" [0-9][0-9]:[0-5][0-9]", " XX:XX", actual)
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(
                r" fe80::[0-9a-f: ]+", " fe80::XXXX:XXXX:XXXX:XXXX   ", actual
            )
            # Remove trailing spaces on all lines
            actual = "\n".join([line.rstrip() for line in actual.splitlines()])

            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual SHOW IPv6 RIPng",
                title2="expected SHOW IPv6 RIPng",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write("r%s failed SHOW IPv6 RIPng check:\n%s\n" % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IPv6 RIPng failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # CLI(net)


def test_zebra_ipv6_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifying Zebra IPv6 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = "%s/r%s/show_ipv6_route.ref" % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ("\n".join(expected.splitlines()) + "\n").splitlines(1)

            # Actual output from router
            actual = (
                net["r%s" % i]
                .cmd('vtysh -c "show ipv6 route" 2> /dev/null | grep "^R"')
                .rstrip()
            )
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Drop timers on end of line
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ("\n".join(actual.splitlines()) + "\n").splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(
                actual,
                expected,
                title1="actual Zebra IPv6 routing table",
                title2="expected Zebra IPv6 routing table",
            )

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write(
                    "r%s failed Zebra IPv6 Routing Table Check:\n%s\n" % (i, diff)
                )
                failures += 1
            else:
                print("r%s ok" % i)

            assert (
                failures == 0
            ), "Zebra IPv6 Routing Table verification failed for router r%s:\n%s" % (
                i,
                diff,
            )

    # Make sure that all daemons are running
    for i in range(1, 4):
        fatal_error = net["r%s" % i].checkRouterRunning()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR daemons, uncomment the next line
    # CLI(net)


def test_shutdown_check_stderr():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        print(
            "SKIPPED final check on StdErr output: Disabled (TOPOTESTS_CHECK_STDERR undefined)\n"
        )
        pytest.skip("Skipping test for Stderr output")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifying unexpected STDERR output from daemons")
    print("******************************************\n")

    net["r1"].stopRouter()

    log = net["r1"].getStdErr("ripngd")
    if log:
        print("\nRIPngd StdErr Log:\n" + log)
    log = net["r1"].getStdErr("zebra")
    if log:
        print("\nZebra StdErr Log:\n" + log)


def test_shutdown_check_memleak():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    if os.environ.get("TOPOTESTS_CHECK_MEMLEAK") is None:
        print(
            "SKIPPED final check on Memory leaks: Disabled (TOPOTESTS_CHECK_MEMLEAK undefined)\n"
        )
        pytest.skip("Skipping test for memory leaks")

    thisDir = os.path.dirname(os.path.realpath(__file__))

    net["r1"].stopRouter()
    net["r1"].report_memory_leaks(
        os.environ.get("TOPOTESTS_CHECK_MEMLEAK"), os.path.basename(__file__)
    )


if __name__ == "__main__":

    setLogLevel("info")
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
